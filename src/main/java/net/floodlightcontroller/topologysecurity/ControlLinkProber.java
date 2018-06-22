package net.floodlightcontroller.topologysecurity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.topologysecurity.TopoloyUpdateChecker.PortManager;
import net.floodlightcontroller.util.MACAddress;

//the class is to measure the latency between SDN Controllers and activated switches
public class ControlLinkProber implements IOFMessageListener, IOFSwitchListener, 
							   ILinkDelayProberService, IFloodlightModule{

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;

	//record the last time send out probe packets
	HashMap<Long, Long>  lastSendRecord;
	
	//store latest 3 delay for links between controller and switches (with dpid)
	private ConcurrentHashMap<Long, Queue<Long>> delayStore;
	
	//the IPs and MACs are used to probe control link
	String originIP = "10.255.0.1";
	MACAddress originMAC = MACAddress.valueOf("aa:aa:aa:aa:aa:aa");
	String probeIP = "10.255.0.2";
	MACAddress probeMAC = MACAddress.valueOf("bb:bb:bb:bb:bb:bb");
	
	protected class LinkProbeWorker implements Runnable {
		long switchID = 0;
		long delay;
		
		public LinkProbeWorker(long swID, long d){
			switchID = swID;
			delay = d;
		}
		
		@Override
		public void run() {
			//if last probe packet is not consumed, just wait
			while(lastSendRecord.containsKey(switchID)) {
			}
			
			//send out packet-out message for probing
			IOFSwitch sw = floodlightProvider.getSwitch(switchID);
		
	        if (sw == null) {// if the switch is offline, do nothing
	            return;
	        }
	        
	        //send out packet-out to probe delay in the control link
	        OFPacketOut po = generateProbeMessage();
	        
	        //logger.info("Send out delay probe message");
	        try {
	            if (delay > 0) {
		        	Thread.sleep(delay);
		        }
		        
	            sw.write(po, null);
	            sw.flush();
	            lastSendRecord.put(switchID, System.nanoTime());
	            
	        } catch (Exception e) {
	        	logger.error("Cannot write probing message to SW " + switchID);
	        }
		}
		
	}
	
	
	public ControlLinkProber(){
		lastSendRecord = new HashMap<>();
		//probeThread = new HashMap<>();
	}
	

	private OFPacketOut generateProbeMessage() {
		
		String ControllerIP = "10.0.0.100"; // TODO: retrieve controller IP from Floodlight API
		
		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                .getMessage(OFType.PACKET_OUT);
		
		
		IPacket packet = new IPv4()
        .setProtocol(IPv4.PROTOCOL_ICMP)
        .setSourceAddress(ControllerIP)
        .setDestinationAddress(probeIP) 
        .setPayload(new ICMP()
                        .setIcmpType((byte) 8)
                        .setIcmpCode((byte) 0)
                        .setPayload(new Data(new byte[]
                                    {0x76, (byte) 0xf2, 0x0, 0x2, 0x1, 0x1, 0x1}))
                   );
      
        Ethernet ethernet = new Ethernet().setSourceMACAddress(originMAC.toBytes())
        						 .setDestinationMACAddress(probeMAC.toBytes())
        						 .setEtherType(Ethernet.TYPE_IPv4);
        
       ethernet.setPayload(packet);
        
        byte[] data = ethernet.serialize();
        
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue(),
                  (short)0xFFFF));
        
        po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        po.setInPort(OFPort.OFPP_NONE);
        po.setPacketData(data);
        po.setActions(actions);
        po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
        
        // set data and data length
        po.setLengthU(OFPacketOut.MINIMUM_LENGTH + data.length + po.getActionsLength() );

		return po;
		
	}

	  protected Command handlePacketIn(long sw, OFPacketIn pi,
              FloodlightContext cntx) {
		  
		  Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                  IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		  
		  //xray: debug
		//  logger.info("The delay between Controller and SW " + sw + " is " 
		//		  			+ getControlLinkDelay(sw)/1000 + " microseconds");
		  
		  if(eth.getPayload() instanceof IPv4) {
			  IPv4 packet = (IPv4) eth.getPayload();
			  
			  long sentTime;
			  long delay;
			  
			  if (originMAC.equals(eth.getSourceMAC()) &&
					  probeMAC.equals(eth.getDestinationMAC())) {
				  
				  if (lastSendRecord.containsKey(sw))
					  sentTime = lastSendRecord.get(sw);
				  else {
					  return Command.STOP;
				  }
				  
				  //get one-way delay
				  delay = (System.nanoTime() - sentTime)/2;
				  
				  Queue<Long> delayQ = delayStore.get(sw);
			
				  if(delayQ == null) {
					  delayQ = new LinkedList<Long>();
			
				  }
				  else{
					  while(delayQ.size() >= 3) 
						  delayQ.remove();
				  }
				  delayQ.add(delay);
				  
				  //update delay store for switches
				  delayStore.put(sw, delayQ);
				  lastSendRecord.remove(sw);

				  //default delay for probing is 5s
				  long tDelay;
				  if (delay/1000000 > 500) {
					  tDelay = 0;
				  }
				  else {
					  tDelay = 5000 - delay/1000000;
				  }
				  
				  //logger.info("delay in ms: " + tDelay);
				  (new Thread(new LinkProbeWorker(sw, tDelay))).start();
				  
	
				  				  
				  return Command.STOP;

			  }
		  }
		  
		  return Command.CONTINUE;
	  }
	

	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "Control Link Prober";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		   return (type.equals(OFType.PACKET_IN) &&
	                (name.equals("Port Manager")));
	}

	@Override
	public void switchAdded(long switchId) {
		if(!delayStore.containsKey(switchId)){
			Queue<Long> delays = new LinkedList<Long>();
			
			delayStore.put(switchId, delays);
		}
		
		(new Thread(new LinkProbeWorker(switchId, 0))).start();			
		
		
	}

	@Override
	public void switchRemoved(long swID) {
		  logger.info("remove delay store");

		delayStore.remove(swID);
		lastSendRecord.remove(swID);
		//probeThread.remove(swID);
	}

	@Override
	public void switchActivated(long switchId) {

	}

	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchChanged(long switchId) {
		// TODO Auto-generated method stub
		
	}

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg,
                           FloodlightContext cntx) {
        switch (msg.getType()) {
            case PACKET_IN:
                return this.handlePacketIn(sw.getId(), (OFPacketIn) msg,
                                           cntx);
            default:
                break;
        }
        return Command.CONTINUE;
    }

	@Override
	public Collection getModuleServices() {
		 Collection<Class<? extends IFloodlightService>> l =
	                new ArrayList<Class<? extends IFloodlightService>>();
	     l.add(ILinkDelayProberService.class);
	        // l.add(ITopologyService.class);
	     return l;
	}

	@Override
	public Map getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m =
                new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
        // We are the class that implements the service
        m.put(ILinkDelayProberService.class, this);
        return m;
	}

	@Override
	public Collection getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		
		logger = (Logger) LoggerFactory.getLogger(ControlLinkProber.class);

		delayStore = new ConcurrentHashMap<>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
	    floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFSwitchListener(this);
	}

	 @Override
	 public long getControlLinkDelay(long swID) {
		  Queue<Long> delayQ = delayStore.get(swID);
		  
		  //if we can not find delay queue for the switch, we just return 0
		  if(delayQ == null || delayQ.isEmpty()) {
			  return 0;
		  }
		  
		  long sum = 0;
		  
		  int size = delayQ.size();
		  

		  for(long i : delayQ) {
			  sum += i;
		  }

		  return sum/size ; 

	 }

}