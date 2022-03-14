
// Log constants
var LOG_LEVELS = {
  "Error": 0,
  "Warn": 1,
  "Info": 2,
  "Debug": 3,
  "Verbose": 4,
}

var LOG_LEVEL = LOG_LEVELS.Info

// Log functions

function logFilter(message, log_level){
  if(log_level <= LOG_LEVEL){
    send(JSON.stringify({"payload": message, "log": true}));
  }
}

function log(message, log_level=LOG_LEVELS.Debug){
  let log_message = "";
  switch(log_level){
    case LOG_LEVELS.Error:
      log_message = `[Error] - ${message}`;
      break;
    case LOG_LEVELS.Warn:
      log_message = `[Warn] - ${message}`;
      break;
    case LOG_LEVELS.Info:
      log_message = `[Info] - ${message}`;
      break;
    case LOG_LEVELS.Debug:
      log_message = `[Debug] - ${message}`;
      break;
    case LOG_LEVELS.Verbose:
      log_message = `[Verbose] - ${message}`;
      break;
  }
  logFilter(log_message, log_level);
}

function resolveName(fullFunctionName) {
  let moduleName = fullFunctionName.split('!')[0];
  let functionName = fullFunctionName.split('!')[1];
  let binaryName = moduleName + ".dll"; // We guess that the loaded module ends with .dll

  if (fullFunctionName in resolvedAddresses) {
    return resolvedAddresses[fullFunctionName];
  }

  log("resolveName " + fullFunctionName);
  log("Module.findExportByName " + binaryName + " " + fullFunctionName);
  var addr = 0;
  addr = Module.findExportByName(binaryName, functionName);

  if (!addr || addr.isNull()) {
    if (!(binaryName in loadedModules)) {
      log("DebugSymbol.loadModule " + binaryName);
      try {
        DebugSymbol.load(binaryName);
      } catch (err) {
        // Something went worng => Bail out
        return 0;
      }
      log("DebugSymbol.load finished");
      loadedModules[binaryName] = 1;
    }

    try {
      addr = DebugSymbol.getFunctionByName(fullFunctionName);
    } catch (err) {
      log(err);
    }
  }

  log(`Addr value: ${addr}`);

  if(addr == 0 || addr == null){
    // We couldn't find the offset in all "traditional" ways. We have to do some heavy lifting
    log(`Heavy lifting for ${functionName}`);
    let send_obj = {"action": "resolve_pointer_name", "module": binaryName, "functionName": functionName};
    send(JSON.stringify(send_obj));
    let op = recv('input', function(value) {
      addr = ptr(value.payload);
    });
    op.wait();
  }

  resolvedAddresses[functionName] = addr;
  return addr;
}

function loadSymbolsForFile(module){
  log(`Loading symbols for ${module.name}`, LOG_LEVELS.Info);
  let result = {"error": ""};
  let send_obj = {"action": "load_file_symbols", "module": module};
    send(JSON.stringify(send_obj));
    let op = recv('input', function(value) {
      result = value.payload;
    });
    op.wait()
    if(result["error"] != ""){
      log(`Symbols for ${module.name} couldn't be loaded\r\n\tError - ${result["error"]}`, LOG_LEVELS.Info);
    } else {
      log(`Symbols for ${module.name} loaded => ${result["functions_in_symbol"]} functions`, LOG_LEVELS.Info);
    }
}

function resolvePointersToFunctionName(pointerList){
    let result = {};
    let return_list = [];
    let resolvedCounter = 0;
    log(`pointerList => ${pointerList}`, LOG_LEVELS.Debug);
    pointerList.forEach((key)=>{
      result[key] = "";
      if(POINTERTS_TO_FUNCTION.hasOwnProperty(key)){
        result[key] = POINTERTS_TO_FUNCTION[key];
        resolvedCounter += 1;
      }
    }
    );

    log(`result pre-call => ${result}`, LOG_LEVELS.Debug);
    
    if(pointerList.length != resolvedCounter){
      let send_obj = {"action": "resolve_functions", "pointerList": result};
      send(JSON.stringify(send_obj));
      let op = recv('input', function(value) {
        result = value.payload;
      });
      op.wait();
    }
    
    Object.keys(result).forEach((key, index, array)=>{
      if(!POINTERTS_TO_FUNCTION.hasOwnProperty(key)){
        POINTERTS_TO_FUNCTION[key] = result[key];
      }
      if(result[key] != ""){
        return_list.push(result[key]);
      }
      else{
        return_list.push(key);
      }
    });
    log(`Returns list ${return_list}`, LOG_LEVELS.Debug);
    return return_list;
}

// Globals
var loadedModules = {}
var resolvedAddresses = {}
var POINTERTS_TO_FUNCTION = {}
// Don't change the line below  - the 'FUNCTION_LIST' is replaced by the python script
let functionToHookInBulk = FUNCTION_LIST; 

//
// Start of main logic

// Remove previous  hooks
Interceptor.detachAll();

// Enumerating and iterating over all loaded modules and load modules symbols
var LOADED_MODULES = Process.enumerateModules();
setImmediate(()=>{
  LOADED_MODULES.forEach((moduleObj)=>{
    loadSymbolsForFile(moduleObj);
  });
  setHooks();
});

function setHooks(){
  // Iterating through the list of functions to hook
  functionToHookInBulk.forEach((functionName,index,array)=>{
      try{
          let functionResolvedPointer = resolveName(functionName);
          if (undefined != functionResolvedPointer && null != functionResolvedPointer && 0x0 != functionResolvedPointer){
            log(`[+] Function - ${functionName} resolved => functionResolvedPointer - ${functionResolvedPointer}`, LOG_LEVELS.Info);
              Interceptor.attach(functionResolvedPointer,	{
                  onEnter: function(args){
                      log(`[+] Called ${array[index]}`, LOG_LEVELS.Info);
                      // Reads 10 args even though not all functions have that many args
                      // We better get more args than getting less, I guess.
                      // Feel free to change this value.
                      let numberOfArgsToRead = 10;
                      let argsString = "";
                      for(var i = 0; i < numberOfArgsToRead; i++){
                        try{
                          argsString += `args[${i}]->${args[i]}, `;
                        } catch{
                          log(`Couldn't get args ${i}}`, LOG_LEVELS.Error);
                        }
                      }
                      log(argsString, LOG_LEVELS.Info);
                      try{
                        let backtrace = resolvePointersToFunctionName(Thread.backtrace(this.context, Backtracer.FUZZY));
                        log(`*** Backtrace ***\r\n${backtrace}\r\n`, LOG_LEVELS.Info);
                      } catch(err) {
                        log(`Failed to get the backtrace - Error ${err}}`, LOG_LEVELS.Error);
                      }
                  }
              });
          } else {
            log(`[-] Failed to resolve function - ${functionName} => functionResolvedPointer - ${functionResolvedPointer}`, LOG_LEVELS.Info);
          }
      } catch(error){
          log(`${error}`, LOG_LEVELS.Error);
      }
  });
}