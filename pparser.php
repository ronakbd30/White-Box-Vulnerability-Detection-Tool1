<?php
require 'bootstrap.php';
$parser = new PhpParser\Parser(new PhpParser\Lexer);
$nodeDumper = new PhpParser\NodeDumper;
//$file = file_get_contents("hello.php");
$file = file_get_contents($argv[1]);
$flag = 0;
try{
    $stmts = $parser->parse($file);
    $flag = false;
    if(count($stmts) == 0 ){
        echo "No parsed statements found";
    }
    else {
        echo "\n"."{  \"data\":\n".$nodeDumper->dump($stmts)."}";
    }
}
catch(PhpParser\Error $e){
    echo "Error happened:". $e->getMessage();
}
?>
