import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.lang.Object;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.*;
import org.json.simple.parser.JSONParser;

import java.lang.*;
class Program{
}
interface Handlers {
	public boolean handler(JSONObject node);
	public Hashtable<String, String> getTarget(JSONObject node);
}
class Sink_Echo implements Handlers {
	public boolean handler(JSONObject node){
		boolean isVulnerable = false;
		try{
			JSONArray stmts = (JSONArray) node.get("exprs");
			
			Iterator i = stmts.iterator();
			
			while(i.hasNext()){
				
				JSONObject stmt = (JSONObject)i.next();
				boolean result = tainter(stmt);
				if(result){
					isVulnerable = true;
					break;
				}
			}
		}
		catch(Exception ex){}
		
		return isVulnerable;
	}
	public Hashtable<String, String> getTarget(JSONObject node){
		return null;
	}
	static boolean  tainter(JSONObject stmt){
		boolean result =false ;
		
		try{
			if(stmt.containsKey("name")){
				//check for the variable/function name is in tainted list
				String identifier = stmt.get("name").toString();
				if(Engine.tainted.contains(identifier))
					result = true;
			}
			else if(stmt.containsKey("title")){
				result = tainter((JSONObject)stmt.get("value"));
			}
			else {
				// iterate through all the properties, whose name we dont want to know
				Iterator keys = stmt.entrySet().iterator();
				while(keys.hasNext()){
					JSONObject p_value = (JSONObject)keys.next();
					result = tainter(p_value);
				}
			}
		}
		catch(Exception e){
			System.out.println("error in tainter function");
		}
		
		
		return result;
	}
}
class Sink_Func implements Handlers {
	public boolean handler(JSONObject node){
		boolean isVulnerable = false;
		//for functions we need to arguments , if they take any tainted object as parameters
		try{
			JSONArray args = (JSONArray)node.get("args");
			Iterator i = args.iterator();
			
			while(i.hasNext()){
				JSONObject arg = (JSONObject)i.next();
				if(!arg.get("title").equals("Arg")) continue;
				JSONObject argValue = (JSONObject) ((JSONObject)arg.get("value")).get("value");
			
				if(argValue.get("title").equals("Expr_Variable") && Engine.tainted.contains(((JSONObject)argValue.get("value")).get("name").toString())){
					isVulnerable = true;
					break;
				}
				
			}
		}
		catch(Exception je){
		
		}
		
		
		return isVulnerable;
	}
	public Hashtable<String, String> getTarget(JSONObject node){
		return null;
	}
}
class Stmt_Function implements Handlers{
	public JSONArray callingParams = null;
	public String funName = null;
	public Hashtable <String,String>local_tainted = new Hashtable<String,String>();
	
	public String localTainter(JSONObject stmt)
	{
		String identifier=null;;
	
		try{
			if(stmt.containsKey("name"))
			{
				//check for the variable/function name is in tainted list
				 identifier = stmt.get("name").toString();
				 return identifier;
				
			}
			else if(stmt.containsKey("title"))
			{
				return localTainter((JSONObject)stmt.get("value"));
				
			}
			else 
			{
				// iterate through all the properties, whose name we dont want to know
				Iterator keys = stmt.keySet().iterator();
				while(keys.hasNext())
				{
					JSONObject p_value = (JSONObject)keys.next();
					return localTainter(p_value);
				}
			}
	  }
		catch(Exception e){
			System.out.println("error in tainter function"+e);
		}
		return identifier;
}
	
	
	
	public boolean fetchAndParseFunctionDefinition(JSONObject node){
		
		// parsing inputParams to get the parameters of function call
				boolean isTainted = false;
				ArrayList<String> cp = new ArrayList<String>();
				Iterator i1 = callingParams.iterator();
				// iterate through all the calling paramters
				while(i1.hasNext()){
					JSONObject param = (JSONObject)i1.next();
					String name = ((JSONObject)((JSONObject)((JSONObject)param.get("value")).get("value")).get("value")).get("name").toString();
					cp.add(name);
				}
				Engine.tainted.add("#");
				//System.out.println(Engine.tainted.toString());
				// iterate through all the formal parameters and check if they are tainted
				JSONArray params = (JSONArray)node.get("params");
				Iterator i2= params.iterator();
				int index = 0;
				while(i2.hasNext()){
				
					JSONObject param = (JSONObject)i2.next();
					String name = ((JSONObject)param.get("value")).get("name").toString();
					
					if(Engine.tainted.contains(cp.get(index))){
						Engine.tainted.add(name);
					}
					index++;
				}
				//System.out.println(this.local_tainted.toString());
				//System.out.println(Engine.tainted.toString());
				// parsing the function definition statements
				JSONArray stmts = (JSONArray)node.get("stmts");
				Iterator s_i=stmts.iterator();
				ArrayList<String> globalVariables=new ArrayList<String>();
				ArrayList<String> tempTainted=new ArrayList<String>();
				// iterate through each statement for the function
				while(s_i.hasNext()){
					JsonParser.statement_counter++;
					//System.out.println(JsonParser.statement_counter);
		        	JSONObject stmt = (JSONObject)s_i.next();
		        	
		        	if(Engine.sink_statements.containsKey(stmt.get("title"))){
		        		
		        		//System.out.println(JsonParser.statement_counter);
		        		if(stmt.get("title").toString().equals("Stmt_Echo")){
		        			JSONObject abc=(JSONObject) stmt.get("value");
			        		JSONArray statement = (JSONArray)abc.get("exprs");
			        		Iterator i = statement.iterator();
			        		while(i.hasNext()){
			        			//System.out.println("In 2");
			        			JSONObject st = (JSONObject)i.next();
			        			 String temp=localTainter(st);
			        			 if(temp!=null){
			        				// System.out.println("In 6");
			        				 if(globalVariables.contains(temp)){
			        					// System.out.println("In 3");
			        					 if(Engine.tainted.contains(temp))
			        						 System.out.println("Vulnerability Found at statement:"+ JsonParser.statement_counter + "  "+stmt.get("title"));
			        				 }
			        				 else{
			        					 //System.out.println("In4");
			        					 int counter = Engine.tainted.size();
		            						while(!Engine.tainted.get(--counter).equals("#")){
		            							//System.out.println("in 5");
			            						if(Engine.tainted.get(counter).equals(temp)){
			            							System.out.println("Vulnerability Found at statement:"+ JsonParser.statement_counter + "  "+stmt.get("title"));
			            							break;
			            						}	
			            						
			            					}	
			        				}
			        			}
			        			 
			        			 
			     	       }
		        		}
		        		else {
		        			Handlers handlerObj = (Handlers)Engine.getHandler(stmt.get("title").toString());
			        		boolean vulnerable = handlerObj.handler((JSONObject)stmt.get("value"));
			        		if(vulnerable == true){
			        			System.out.println("Vulnerability Found:" + stmt);
			        			//System.out.println("Stmt No:"+ stmt_line);
			        		}
		        		}
		        		
		        		
		        		
		        	
		        	}  	
		        	
		        	
		        	else if(stmt.get("title").equals("Stmt_Global")){
		        		
		        			//JSONArray globalVarName = (JSo)((JSONObject)node.get("value")).get("vars"));
		        			JSONObject obj1=((JSONObject)stmt.get("value"));
		        			JSONArray varArray=((JSONArray)obj1.get("vars"));
		        			
		        			Iterator i3= varArray.iterator();
		        			int index1 = 0;
		        					        			
		        			while(i3.hasNext())
		        			{
		        				JSONObject param=(JSONObject)i3.next();
		        				String name=((JSONObject)param.get("value")).get("name").toString();
		        				globalVariables.add(name);
		        			}     		
		           	}
		        	
		        	else if(stmt.get("title").equals("Stmt_Return"))
	        		{
	        			JSONObject n = (JSONObject)stmt.get("value");
	        			JSONObject innExpr = (JSONObject)n.get("expr");
	        			String innExprTitle=(String)innExpr.get("title");
	        			boolean isExprTainted = false;
	        			// working with straight expressions ( non-nested expressions)
	        		   	if(innExprTitle.equals("Expr_Variable")){
	        		   		 
	        			   	 String innExprName=((JSONObject)innExpr.get("value")).get("name").toString();
	        			   	 // TODO: Check in global list of tainted n move accordingly.
	        			   	 if(Engine.source_statements.containsKey(innExprName) || this.local_tainted.containsKey(innExprName) || Engine.tainted.contains(innExprName)) isTainted = true;
	        			   	 
	        			}
	        		   	else if(innExprTitle.equals("Scalar_String")){
	        		   		return isExprTainted;
	        		   	}	   	 
	        		   	else if(innExprTitle.equals("Expr_ArrayDimFetch")){
	        		   		 String innExprName=((JSONObject)((JSONObject)((JSONObject)innExpr.get("value")).get("var")).get("value")).get("name").toString();
	        		   		 //TODO check if _GET then add innVarName to taint list
	        		   		 if(Engine.source_statements.containsKey(innExprName) || this.local_tainted.containsKey(innExprName)) isTainted = true;
	        		   	}	   	 
	        		   	/*else if(innExprTitle.equals("Expr_FuncCall")){
	        		   		 //TODO: List of system defined functions.
	        		   		 //TODO: List of scannedfunctions
	        		   	}*/
	        		   	else if(Engine.getHandler(innExprTitle) != null)
	        		   	{
	        		   		Handlers obj = (Handlers)Engine.getHandler(innExprTitle);
	        		   		boolean result =  obj.handler((JSONObject)innExpr.get("value"));
	        		   		if(result == true) {
	        		   			Hashtable<String, String> var= obj.getTarget((JSONObject)innExpr.get("value"));
	        		   			if(var != null)
	        		   				Engine.tainted.add(var.keys().nextElement());
	        		   		}
	        		   		else{
	            				// if the identifier is already tainted, and new value is not tainted. remove from the tainted list
	            					Hashtable<String, String> var = obj.getTarget((JSONObject)stmt.get("value"));		            					
	            					
	            					if(var!=null){
	            						int counter = Engine.tainted.size();
	            						while(!Engine.tainted.get(--counter).equals("#")){
		            						if(Engine.tainted.get(counter).equals(var.keys().nextElement())){
		            							Engine.tainted.remove(counter);
		            						}	            							
		            					}
	            					}
	            				}
	        		   		isTainted = result;			        		   		
	        		   	}			        		        		   	
	        		}
		        	
		        	else{
		        		if(Engine.operations.containsKey(stmt.get("title"))){
		        			        				
		        				if(Engine.getHandler(stmt.get("title").toString()) != null){
		        				JSONObject innValue = (JSONObject)stmt.get("value");
		        				Handlers obj = (Handlers)Engine.getHandler(stmt.get("title").toString());
		        				boolean tainted = obj.handler(innValue);
		        				
		        				// this variable is tainted
		        				if(tainted == true) { 
		                    		//System.out.println("its tainted");
		        					
		        					Hashtable<String, String> var= obj.getTarget(innValue);
		        					String K = var.keys().nextElement();
		        					if(var!=null){
		        						if(globalVariables.contains(K)){
		        							int counter=0;
		        							//System.out.println(Engine.tainted.toString());
		        							while(!Engine.tainted.get(counter).equals("#")){
		        								if(Engine.tainted.get(counter).equals(K))
		        									break;	
		        								counter++;
		        							}
		        							
		        							if(Engine.tainted.get(counter).equals("#")){
		        								Engine.tainted.add(counter, K);
		        							}       							
		        						}
		        						else{
		        							//System.out.println(K);
				        		   			Engine.tainted.add(K);	
		        						}	
		        				    }		        					
		                    	}
		        				else{
		        				// if the identifier is already tainted, and new value is not tainted. remove from the tainted list
		        					Hashtable<String, String> var = obj.getTarget(innValue);
		        					if(var!=null){
		        						if(globalVariables.contains(var)){
		        							int counter = 0;
		            						while(!Engine.tainted.get(counter).equals("#")){
			            						if(Engine.tainted.get(counter).equals(var.keys().nextElement())){
			            							Engine.tainted.remove(counter);
			            							//System.out.println("No##");
			            						}	
			            						counter++;
			            					}
		        						}
		        						else{
	            						int counter = Engine.tainted.size();
	            						while(!Engine.tainted.get(--counter).equals("#")){
		            						if(Engine.tainted.get(counter).equals(var.keys().nextElement())){
		            							Engine.tainted.remove(counter);
		            							break;
		            							//System.out.println("No##");
		            						}	            							
		            					}
	            						
		        					}
	            				}
		        					
		        					//System.out.println("No##");
		        				}
		        			}  
		        		}
		        	}		            	            
		        }
			// before returning, remove local tainted variables 
			int counter = Engine.tainted.size();
			while(!Engine.tainted.get(--counter).equals("#")){
				Engine.tainted.remove(counter);
			}
			Engine.tainted.remove(counter);
			return isTainted;
	}
	public boolean handler(JSONObject node){
		//System.out.println(JsonParser.statement_counter);
		boolean result = false;
		this.callingParams = (JSONArray)node.get("args");
		
		// parsing name for the function
		JSONArray funNameParts = (JSONArray)((JSONObject)((JSONObject)node.get("name")).get("value")).get("parts");
		String funName = funNameParts.get(0).toString();
		this.funName = funName;
		// fetching function definition
		if(Engine.sink_statements.containsKey(this.funName)){
    		//check for vulnerability
    		Handlers handlerObj = (Handlers)Engine.getHandler(this.funName);
    		boolean vulnerable = handlerObj.handler((JSONObject)node);
    		if(vulnerable == true){
    			System.out.println("Vulnerability Found at statement: "+JsonParser.statement_counter+" mysql_query");
    			result = true;
    			//System.out.println("Stmt No:"+ stmt_line);
    		}
    		
    	}
		else {
			JSONObject obj = Engine.func_def.get(funName);
			if(obj != null)result = fetchAndParseFunctionDefinition(obj);
		}
		return result;
	}
	public Hashtable<String, String> getTarget(JSONObject node){
		if(node == null) { 
			System.out.println("Null Return: getTarget function Stmt_FuncCall");
			return null; 
		}
		JSONArray funNameParts = (JSONArray)((JSONObject)((JSONObject)node.get("name")).get("value")).get("parts");
		Hashtable<String, String> result = new Hashtable<String, String>();
		result.put(funNameParts.get(0).toString(), "Expr_FuncCall");
		return null;			
	}
	
}
class Stmt_Assign implements Handlers{
	public boolean handler(JSONObject node){
		
		JSONObject innExpr = (JSONObject)node.get("expr");
		String innExprTitle=(String)innExpr.get("title");
		boolean isExprTainted = false;
		
		// working with straight expressions ( non-nested expressions)
	   	if(innExprTitle.equals("Expr_Variable")){
	   		 
		   	 String innExprName=((JSONObject)innExpr.get("value")).get("name").toString();
		   	 // TODO: Check in global list of tainted n move accordingly.
		   	 if(Engine.source_statements.containsKey(innExprName)) isExprTainted = true;
		   	 else if(Engine.tainted.contains(innExprName)) isExprTainted = true;
		   	 
		}	   	 
	   	else if(innExprTitle.equals("Expr_ArrayDimFetch")){
	   		 String innExprName=((JSONObject)((JSONObject)((JSONObject)innExpr.get("value")).get("var")).get("value")).get("name").toString();
	   		 //TODO check if _GET then add innVarName to taint list
	   		 if(Engine.source_statements.containsKey(innExprName)) isExprTainted = true;
	   	}	   	 
	   	
	   	else if(Engine.getHandler(innExprTitle) != null){
	   		
	   		Handlers obj = (Handlers)Engine.getHandler(innExprTitle);
	   		boolean result =  obj.handler((JSONObject)innExpr.get("value"));
	   		if(result == true) {
	   			Hashtable<String, String> var= obj.getTarget((JSONObject)innExpr.get("value"));
	   			if(var != null)
	   				Engine.tainted.add(var.keys().nextElement());
	   		}
	   		isExprTainted = result;	
	   		
	   	}	
		return isExprTainted;
	}
	public Hashtable<String, String> getTarget(JSONObject node){
		if(node == null) { 
			System.out.println("Null Return: getTarget function Stmt_Assign");
			return null; 
		}
		JSONObject lhs = (JSONObject)node.get("var");
		Hashtable<String, String> result = new Hashtable<String, String>();
		result.put(((JSONObject)(lhs).get("value")).get("name").toString(), "Expr_Assign");
		return result;	
		//return ((JSONObject)(lhs).get("value")).get("name").toString();		
	}
}


class Engine {
	// contains all the sources that can bring taint objects in the program
	public static Hashtable<String,String> source_statements = new Hashtable<String,String>();
	// contains all the api functions that can become vulnerability if parameters are tainted
	public static Hashtable <String,String>sink_statements = new Hashtable<String,String>();
	// metadata, given a statement which all parameters need to be checked for taint propagation [key: statment, value: Para]
	public static Hashtable<String,Object> operations = new Hashtable<String,Object>();
	// contains computed tainted objects [key: identifier, value: TYPE]
	public static ArrayList<String>tainted = new ArrayList<String>();
	
	public static Hashtable<String,JSONObject>func_def=new Hashtable<String, JSONObject>(); 
	
	public Engine(){
		init_sourceVector();
		init_sinkVector();
		init_operations();
		this.tainted = new ArrayList<String>();
	}

	

	public static boolean checkExprTaint(JSONObject value){
		boolean isTainted = false;
		
		JSONArray stmts = (JSONArray) value.get("exprs");
		Iterator i = stmts.iterator();
		while(i.hasNext()){
			JSONObject stmt = (JSONObject)i.next();
			boolean result = tainter(stmt);
			if(result){
				isTainted = true;
				break;
			}
		}
		return isTainted;
	}	
		
	public static boolean  tainter(JSONObject stmt)
	{
		boolean result= false ;
		try{
			if(stmt.containsKey("name")){
				//check for the variable/function name is in tainted list
				String identifier = stmt.get("name").toString();
				if(tainted.contains(identifier))
					result = true;
			}
			else if(stmt.containsKey("title")){
				result = tainter((JSONObject)stmt.get("value"));
			}
			else {
				// iterate through all the properties, whose name we dont want to know
				Iterator keys = stmt.keySet().iterator();
				while(keys.hasNext()){
					JSONObject p_value = (JSONObject)keys.next();
					result = tainter(p_value);
				}
			}
		}
		catch(Exception e){
			System.out.println("error in tainter function"+e);
		}
		return result;
	}
	
	
	public static Object getHandler(String op){
		if(op.equals("Expr_Assign")) return new Stmt_Assign();
		else if(op.equals("Expr_FuncCall")) return new Stmt_Function();	
		else if(op.equals("Stmt_Echo"))return new Sink_Echo();
		else if(op.equals("mysql_query"))return new Sink_Func();
		
		return null;
	}

	//method to store functions in array
	public void storeFunc(JSONArray stmts,Engine e){
    	Iterator i=stmts.iterator();
        // logic for checking taint propagation
        
        while(i.hasNext()){
        	JSONObject stmt = (JSONObject)i.next();
        	if(stmt.containsKey("title") && stmt.get("title").equals("Stmt_Function")){
				JSONObject funObj = (JSONObject)stmt.get("value");
				Engine.func_def.put(e.getFunctionName(funObj), funObj);
			}
        }
    }
	
	//method to get method name
	public String getFunctionName(JSONObject funObj){
		return funObj.get("name").toString();
	}
	
	//method to initialize source vector
	private void init_sourceVector(){
		//source_statements = new Hashtable();
		// initialize with all the possible infection sources
		source_statements.put("_GET","Expr_Variable");
		source_statements.put("_POST","Expr_Variable");
	}
	
	//method to initialize sink vector
	private void init_sinkVector(){
		//sink_statements = new Hashtable();
		sink_statements.put("Stmt_Echo", "exprs");
		sink_statements.put("mysql_query", "args");
		
	}
	
	//method to initialize operations
	private void init_operations(){
		//operations = new Hashtable();
		operations.put("Expr_Assign","");
		operations.put("Stmt_Function","" );
		operations.put("stmt_Global","");
		operations.put("Expr_FuncCall","" );
	}
	
}
















	
