<?php

namespace PhpParser;

class NodeDumper
{
    /**
     * Dumps a node or array.
     *
     * @param array|Node $node Node or array to dump
     *
     * @return string Dumped value
     */
    public function dump($node) {
        if ($node instanceof Node) {
            $r = "\n{\n \"title\"" . ":" . " \"". $node->getType(). "\",". "\n". " \"value\": {\n";

            foreach ($node->getSubNodeNames() as $key) {
                $value = $node->$key;
                if (null === $value) {
                    $r .= "    \"".$key."\"". ":". "null,";
                } elseif (false === $value) {
                    $r .= "    \"".$key."\"". ":"."false,"."";
                } elseif (true === $value) {
                    $r .= 'true';
                } elseif (is_scalar($value)) {
                    $r .= "    \"$key\"". ":"."\"$value\"".",";
                } else {
                    $r .= " \n\"$key\": ".str_replace("\n", "\n   ", $this->dump($value)).",";
                } 
            }
            $r = rtrim($r ,",");
            $r .= "\n  }\n}";
        } elseif (is_array($node)) {
             $r = " [";
            foreach ($node as $key => $value) {
                if (null === $value) {
                    $r .= 'null';
                } elseif (false === $value) {
                    $r .= 'false';
                } elseif (true === $value) {
                    $r .= 'true';
                } elseif (is_scalar($value)) {
                    $r .= "\n\"".$value."\"\n";
                } else {
                    $r .= str_replace("\n", "\n   ", $this->dump($value)).",";
                }
            }
            $r = rtrim($r ,",");
                $r .= "\n ]";
        } else {
            throw new \InvalidArgumentException('Can only dump nodes and arrays.');
        }
        return $r . "\n";
    }
    public function nodedump($node) {
        if (is_array($node)) {
            foreach ($node as $key => $value) {
                $r .= "\n".$this->dump($value).",";
            }
        }
        $r = rtrim($r, ",");
        return $r;
    }
}
