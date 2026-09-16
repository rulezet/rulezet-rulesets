rule TTP_XOR_WriteProcessMemory_cbad {
  strings:
    $key_cbad = { 9c df [2] ae fd [2] a8 c8 [2] 86 c8 [2] b9 d4 }

  condition:
    any of them
}