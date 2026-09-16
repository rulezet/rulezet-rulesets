rule Virus_Hijack_Gen_Trojan_ShellObject_u8Y_aivto4c_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Y@aivto4c_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c500cf83b7c757d6cf0bf5dfdc6c1fdaa901bc0cd11328fe328ef6525525c00"

  strings:
    $s1  = " Make sure your keyboard is compatible with the %s keyboard driver or restart the host computer." fullword ascii
    $s2  = "@&!*@*@(msg.mkskb.vmkbd.required)This virtual machine requires the %s keyboard support driver, which is not currently available." ascii
    $s3  = "MKS Win32: Failed to get the token information, win32 error code (%#x)." fullword ascii
    $s4  = "MKSGrab: Input processing back to normal." fullword ascii
    $s5  = "MKS Win32: Failed to get the length of the token information, win32 error code (%#x)." fullword ascii
    $s6  = "DXGIPresentation: Failed getting the shared handle for presentation resource" fullword ascii
    $s7  = "%s: Unable to get binary's path." fullword ascii
    $s8  = "MKSGrab: Unity grab attempt while already unity grabbing.  Ignored." fullword ascii
    $s9  = "@&!*@*@(msg.mksRemoteMgr.initFailed)Failed to initialize the remote display subsystem." fullword ascii
    $s10 = "MKSGrab: Continuing with previous grab attempt" fullword ascii
    $s11 = "@&!*@*@(msg.mkskb.vmkbd.required)This virtual machine requires the %s keyboard support driver, which is not currently available." ascii
    $s12 = "MKS-RenderMain: Clamping maximum texture size down to RenderOps limit (from %d, to %d)" fullword ascii
    $s13 = "%s: Failed to load OpenSSL config file." fullword ascii
    $s14 = "Adaptor %d: Error fetching data (%d:%s)." fullword ascii
    $s15 = "MKSGrab: Switching grab types from %s to %s: ungrabbing first" fullword ascii
    $s16 = "MKS Win32: Failed window creation for MKSWindowId=%d: Invalid UI Window" fullword ascii
    $s17 = "MKS-RenderMain: Renderer failed to meet minimum required texture size (got=%d, required=%d)" fullword ascii
    $s18 = "MKSGrab: Grab attempt into non input window.  Ignored." fullword ascii
    $s19 = "MKSThread: Failed to create thread" fullword ascii
    $s20 = "MKS Win32: Failed to enable high resolution system timer." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}