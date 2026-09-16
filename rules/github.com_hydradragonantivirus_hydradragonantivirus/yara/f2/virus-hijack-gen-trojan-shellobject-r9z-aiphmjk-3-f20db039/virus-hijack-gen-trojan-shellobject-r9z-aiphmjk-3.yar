rule Virus_Hijack_Gen_Trojan_ShellObject_r9Z_aipHmJk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r9Z@aipHmJk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90c5477cc970bcee468cfd379759765c7e976166fc4f62b4edcde725b1f1c767"

  strings:
    $s1  = "Host: www.google.com" fullword ascii
    $s2  = "%s:%d:%d: This content is not allowed in script element" fullword ascii
    $s3  = ".?AV?$UnboundMethodSlot0@_N$$CBV?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@ggadget@@P8123@BE_NXZ@ggadge" ascii
    $s4  = ".?AV?$UnboundMethodSlot0@PAVDOMNamedNodeMapInterface@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@intern" ascii
    $s5  = ".?AV?$DelegatedMethodSlot1@PAVDOMNodeListInterface@ggadget@@PBDV?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@inter" ascii
    $s6  = ".?AV?$DelegatedMethodSlot0@VVariant@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@2@P8DOMNodeImp" ascii
    $s7  = ".?AV?$DelegatedMethodSlot2@PAVDOMNodeInterface@ggadget@@PAV12@PAV12@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@" ascii
    $s8  = ".?AV?$DelegatedMethodSlot1@PAVDOMNodeInterface@ggadget@@PAV12@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@intern" ascii
    $s9  = ".?AV?$UnboundMethodSlot0@XV?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@ggadget@@P8123@AEXXZ@ggadget@@" fullword ascii
    $s10 = "@2@P8DOMNodeImpl@42@AEPAV12@XZU?$FieldDelegateGetter@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@ggadge" ascii
    $s11 = ".?AV?$DelegatedMethodSlot0@PAVDOMNodeListInterface@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal" ascii
    $s12 = ".?AV?$DelegatedMethodSlot1@PAVDOMNodeInterface@ggadget@@PBDV?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@" ascii
    $s13 = ".?AV?$DelegatedMethodSlot1@PAVDOMNodeInterface@ggadget@@PBDV?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@" ascii
    $s14 = ".?AV?$UnboundMethodSlot0@PAVDOMDocumentInterface@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@2" ascii
    $s15 = ".?AV?$DelegatedMethodSlot0@PAVDOMNodeInterface@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@2@P" ascii
    $s16 = ".?AV?$UnboundMethodSlot0@PAVDOMDocumentInterface@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@2" ascii
    $s17 = ".?AV?$DelegatedMethodSlot0@VVariant@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@2@P8DOMNodeImp" ascii
    $s18 = ".?AV?$UnboundMethodSlot0@PAVDOMNamedNodeMapInterface@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@intern" ascii
    $s19 = ".?AV?$UnboundMethodSlot0@PAVDOMNodeInterface@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@2@P83" ascii
    $s20 = ".?AV?$DelegatedMethodSlot1@XABVVariant@ggadget@@V?$DOMNodeBase@VDOMProcessingInstructionInterface@ggadget@@@internal@2@P8DOMNode" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}