import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class JsonParser{

	static int statement_counter=0;
    public static void main(String args[]) {

    	// let's read
        //readJson("input.json");
        Engine e = new Engine();
        JsonParser j = new JsonParser();
        
        //parse input file, get JSON array of statements
        JSONObject mydata = j.readJSON("input.json");
        JSONArray stmts = (JSONArray) mydata.get("data");
        e.storeFunc(stmts, e);
        Iterator i=stmts.iterator();
        // logic for checking taint propagation
        
        while(i.hasNext()){
        	
        	JSONObject stmt = (JSONObject)i.next();
        	//if(stmt.containsKey("title") && e.operations.containsKey(stmt.get("title").toString())){
            	//JSONObject params = (JSONObject)e.operations.get(stmt.get("title").toString());
        	if(e.sink_statements.containsKey(stmt.get("title"))){
        		statement_counter++;
        		//check for vulnerability
        		boolean vulnerable = Engine.checkExprTaint((JSONObject)stmt.get("value"));
        		if(vulnerable == true){
        			System.out.println("Vulnerability Found at statement:"+ statement_counter + "  "+stmt.get("title"));
        		}
        	}
        		
        	else{
        		if(e.operations.containsKey(stmt.get("title"))){
        			
        			if(e.getHandler(stmt.get("title").toString()) != null){
        				statement_counter++;
        				JSONObject innValue = (JSONObject)stmt.get("value");
        				
        				Handlers obj = (Handlers)Engine.getHandler(stmt.get("title").toString());
        				//System.out.println(obj);
        				
        				boolean tainted = obj.handler(innValue);
        				
        				// this variable is tainted
        				if(tainted == true) { 
                    		//System.out.println("its tainted");
        					//JSONObject input = (JSONObject)innValue.get("value");
        					Hashtable<String, String> var= obj.getTarget(innValue);  
        					if(var != null)
        						Engine.tainted.add(var.keys().nextElement());
                    	
                    	}
        				else{
        				// if the identifier is already tainted, and new value is not tainted. remove from the tainted list
        					Hashtable<String, String> var = obj.getTarget(innValue);

        					if(var != null && Engine.tainted.contains(var.keys().nextElement()))
        						Engine.tainted.remove(var.keys().nextElement());
        				}
        			}
        			
        			
        		}
        		
        	}
        }
      
        
        // condition is true if statement is an operation which can propagate
        System.out.println();
        System.out.print("The list of tainted variables are : ");
        System.out.println(Engine.tainted.toString());
        //System.out.println(Engine.func_def.toString());
       // System.out.println(stmts.size());parts
        
        
    }
    /*
     * Java Method to read JSON From File
     */
        public JSONObject readJSON(String file){
    	JSONParser parser = new JSONParser();
    	try{
    		FileReader reader = new FileReader(file);
    		return (JSONObject) parser.parse(reader);
    	}
    	catch(Exception ex){
    		System.out.println("Error reading the input file");
    		return null;
    	}
    	
    	
    }

}

