rule TTP_XOR_WriteProcessMemory_58ad {
  strings:
    $key_58ad = { 0f df [2] 3d fd [2] 3b c8 [2] 15 c8 [2] 2a d4 }

  condition:
    any of them
}