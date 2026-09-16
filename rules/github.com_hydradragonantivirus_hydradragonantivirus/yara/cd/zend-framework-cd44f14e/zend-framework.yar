rule zend_framework {
  meta:
    author  = "@patrickrolsen"
    maltype = "Zend Framework"
    version = "0.3"
    date    = "12/29/2013"

  strings:
    $mz     = "MZ"      $php    = "<?php"
    $string = "$zend_framework" nocase

  condition:
    not $mz at 0 and $php and $string
}