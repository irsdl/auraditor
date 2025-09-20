/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class ActionResponse {
	@JsonProperty
	public String id;
	@JsonProperty
	public String state;
	@JsonProperty
	public JsonNode returnValue; // UGH can be Array or Object
	@JsonProperty
	public ArrayNode error;
	private ObjectMapper mapper = new ObjectMapper();
	
	public ActionResponse(ObjectNode action){
		if(action.hasNonNull("id")){
			this.id = action.get("id").asText();
		}
		if(action.hasNonNull("state")){
			this.state = action.get("state").asText();
		}
		if(action.hasNonNull("returnValue")){
				this.returnValue = action.get("returnValue");
		}
		if(action.hasNonNull("error")){
			this.error = (ArrayNode)action.get("error");
		}
	}
	
	public String getResponseString() throws JsonProcessingException{
		return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(returnValue);
	}
}
