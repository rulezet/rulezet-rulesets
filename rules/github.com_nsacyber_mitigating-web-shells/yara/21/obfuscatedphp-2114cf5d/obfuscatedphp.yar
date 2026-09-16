rule ObfuscatedPhp
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
        
    strings:
        $eval = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/ nocase          $eval_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/ nocase          $b374k = "'ev'.'al'"
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/          $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/          $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/          $nano = /\$[a-z0-9-_]+\[[^]]+\]\(/         $ninja = /base64_decode[^;]+getallheaders/         $variable_variable = /\${\$[0-9a-zA-z]+}/
        $too_many_chr = /(chr\([\d]+\)\.){8}/          $concat = /(\$[^\n\r]+\.){5}/          $concat_with_spaces = /(\$[^\n\r]+\. ){5}/          $var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
        $comment = /\/\*([^*]|\*[^\/])*\*\/\s*\(/  condition:
        (any of them)
}