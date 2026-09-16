rule TTP_XOR_WriteProcessMemory_58c8 {
  strings:
    $key_58c8 = { 0f ba [2] 3d 98 [2] 3b ad [2] 15 ad [2] 2a b1 }

  condition:
    any of them
}