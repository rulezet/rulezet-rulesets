rule Sanesecurity_BlackEnergy2_Driver {
  strings:
    $a1 = { 7E 4B 54 1A }
    $a2 = { E0 3C 96 A2 }
    $a3 = "IofCompleteRequest" ascii
    $b1 = { 31 A1 44 BC }
    $b2 = "IoAttachDeviceToDeviceStack" ascii
    $b3 = "KeInsertQueueDpc" ascii
    $c1 = { A3 41 FD 66 }
    $c2 = { 61 1E 4E F8 }
    $c3 = "PsCreateSystemThread" ascii

  condition:
    all of ($a*) and 3 of ($b*, $c*)
}