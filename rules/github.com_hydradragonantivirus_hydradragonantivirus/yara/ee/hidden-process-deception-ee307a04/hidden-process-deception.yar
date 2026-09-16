rule Hidden_Process_Deception {
  meta:
    mitre = ""

  strings:
    $a  = "/.com.apple."
    $a1 = "/.google."
    $a2 = ".plist"
    $l1 = "/LaunchAgents/"
    $l2 = "/LaunchDaemons/"
    $A  = "/.com.apple." base64
    $A1 = "/.google." base64
    $A2 = ".plist" base64
    $L1 = "/LaunchAgents/" base64
    $L2 = "/LaunchDaemons/" base64

  condition:
    (2 of ($a*) or 2 of ($A*)) and (1 of ($l*) or 1 of ($L*))
}