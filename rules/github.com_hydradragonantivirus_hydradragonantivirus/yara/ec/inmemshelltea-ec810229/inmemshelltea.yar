rule inMemShellTea: ShellTea {
  meta:
    copyright = "root9b, LLC"

    authors = "Matt Weeks, Dax Morrow"

    description = "ShellTea + PoSlurp PoS Malware in Memory ShellTea"

    reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

    version = "1.0"

    last_modified = "2017-06-27"

  strings:
    $hex1 = { B9 1D C7 12 45 E8 }  
    $hex2 = { B9 52 7E 10 E1 E8 }  
    $hex3 = { B9 CC 11 67 D6 E8 }  
  condition:
    all of them

}