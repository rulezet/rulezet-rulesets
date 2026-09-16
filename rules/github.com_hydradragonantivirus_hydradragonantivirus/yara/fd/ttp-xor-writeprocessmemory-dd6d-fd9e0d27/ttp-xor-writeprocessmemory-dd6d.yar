rule TTP_XOR_WriteProcessMemory_dd6d {
  strings:
    $key_dd6d = { 8a 1f [2] b8 3d [2] be 08 [2] 90 08 [2] af 14 }

  condition:
    any of them
}