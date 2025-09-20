/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.core;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

//TODO perhaps just parse each request directly into this, not this special descriptor thing.
public class ActionRequest {
	// Action definition
	public AuraMessage parent;
	@JsonProperty
	public String id;
	@JsonProperty
	public JsonNode version;	
	@JsonProperty
	public String callingDescriptor;
	@JsonProperty
	public String descriptor;
	@JsonProperty
	public ObjectNode params;
	
	// useful "slices" of the descriptor
	public String calledController;
	public String shortController;
	public String calledMethod;
	private ObjectMapper mapper = new ObjectMapper();
	private MontoyaApi api;
	
	// Actual object
	public ObjectNode root;

	public ActionRequest(ObjectNode node, AuraMessage parent, MontoyaApi api){
		this.root = node;
		this.api = api;
		if(node.hasNonNull("id")){
			this.id = node.get("id").asText();
		}
		
		this.parent = parent;
		
		if(node.hasNonNull("descriptor")){
			this.parseDescriptor();
			this.descriptor = node.get("descriptor").asText();
		}
		
		if(node.hasNonNull("callingDescriptor")){
			this.callingDescriptor = node.get("callingDescriptor").asText();
		}
		
		if(node.hasNonNull("params")){
			this.params = (ObjectNode)node.get("params");
		}
		
		if(node.hasNonNull("version")){
			this.version = node.get("version");
		}
	}
	
	private void parseDescriptor(){
		String descriptor = this.root.get("descriptor").asText();
		int controllerStart = descriptor.indexOf("//")+2; // 2 chars, need to add an extra one
		int methodIndex = descriptor.indexOf('/',controllerStart);
		int methodStart = descriptor.indexOf('$',methodIndex)+1;
		
		this.calledController = (String) descriptor.subSequence(controllerStart, methodIndex);
		this.calledMethod = (String) descriptor.subSequence(methodStart, descriptor.length());
		
		int shortStart = descriptor.lastIndexOf(".",methodIndex);
		if(shortStart == -1){
			this.shortController = this.calledController;
		} else {
			shortStart++;
			this.shortController = descriptor.substring(shortStart,methodIndex);
		}

	}

	public ObjectNode getParams(){
		return (ObjectNode)this.root.get("params");
	}
	
	public void updateParams(ObjectNode newParams){
		this.root.replace("params", newParams);
		this.parent.updateActionRequest(this.id,this);
	}
	
	/**
	 * Updates parameters with raw JSON text, even if it's malformed.
	 * This allows sending requests with invalid JSON if the user chooses to.
	 */
	public void updateParamsWithRawJSON(String rawJsonText) {
		try {
			// First try to parse as valid JSON
			JsonNode parsedParams = mapper.readTree(rawJsonText);
			if (parsedParams.isObject()) {
				updateParams((ObjectNode) parsedParams);
			} else {
				// If it's not an object, wrap it in a simple structure
				ObjectNode wrapper = mapper.createObjectNode();
				wrapper.set("rawContent", parsedParams);
				updateParams(wrapper);
			}
		} catch (JsonProcessingException e) {
			// If JSON parsing fails, create a text node with the raw content
			// This preserves the user's exact input
			ObjectNode rawWrapper = mapper.createObjectNode();
			rawWrapper.put("invalidJSON", rawJsonText);
			updateParams(rawWrapper);
			api.logging().logToError("Using raw JSON due to parse error: " + e.getMessage());
		}
	}
	
	public void updateController(String controllerName){
		this.calledController = controllerName;
		int controllerStart = this.descriptor.indexOf("//")+2;
		String serviceCmpStr = this.descriptor.substring(0, controllerStart);
		this.descriptor = serviceCmpStr + controllerName + "/ACTION$" + this.calledMethod;
		
		int methodIndex = this.descriptor.indexOf('/',controllerStart);
		int shortStart = this.descriptor.lastIndexOf(".", methodIndex);
		if (shortStart == -1){
			this.shortController = this.calledController;
		} else {
			shortStart++;
			this.shortController = this.descriptor.substring(shortStart,methodIndex);
		}
		
		this.root.put("descriptor", descriptor);
		this.parent.updateActionRequest(this.id, this);
	}
	
	public void updateMethod(String methodName){
		this.calledMethod = methodName;
		int methodStart = this.descriptor.indexOf('$')+1;
		this.descriptor = this.descriptor.substring(0, methodStart) + methodName;
		
		this.root.put("descriptor", this.descriptor);
		this.parent.updateActionRequest(this.id,this);
	}
	
	public void updateId(String newId){
		String oldId = this.id;
		this.id = newId;
		this.root.put("id", newId);
		// Update the action request mapping in parent with new ID
		this.parent.updateActionRequestId(oldId, newId, this);
	}
	
	public String getActionString(){
		String minifiedParamStr = "";
		try {
			minifiedParamStr = mapper.writer().writeValueAsString(this.root.get("params"));
		} catch (JsonProcessingException e) {
			api.logging().logToError("JsonProcessingException: " + e.getMessage());
			return this.root.get("params").asText();
		}
		return minifiedParamStr;	
	}
	
	public String getParamString() throws JsonProcessingException{
		return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(this.params);
	}
}
