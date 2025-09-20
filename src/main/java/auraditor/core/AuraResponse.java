/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.core;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class AuraResponse {
	private ObjectMapper mapper = new ObjectMapper();
	public ArrayNode actions;
	public Map<String, ActionResponse> responseActionMap = new HashMap<String,ActionResponse>();
	public ObjectNode auraResponse;
	
	public AuraResponse(){
		
	}
	
	public AuraResponse(String jsonString) throws JsonProcessingException, IOException{
		// skip past the while(1);
		jsonString = jsonString.substring(jsonString.indexOf(';')+1,jsonString.length());
		
		JsonNode result = mapper.readTree(jsonString);
		this.auraResponse = (ObjectNode)result;
		if(result.hasNonNull("actions")){
			this.actions = (ArrayNode)result.get("actions");
			Iterator<JsonNode> actionIter = this.actions.iterator();
			while(actionIter.hasNext()){
				JsonNode next = actionIter.next();
				ActionResponse nextActionResponse = new ActionResponse((ObjectNode) next);
				responseActionMap.put(nextActionResponse.id, nextActionResponse);
			}
		}
		
	}
}
