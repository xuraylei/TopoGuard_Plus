package net.floodlightcontroller.topologysecurity;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface ILinkDelayProberService extends IFloodlightService {

    /**
     * Retrieve the delay between controller and a switch
     */
	public long getControlLinkDelay(long swID);
}
