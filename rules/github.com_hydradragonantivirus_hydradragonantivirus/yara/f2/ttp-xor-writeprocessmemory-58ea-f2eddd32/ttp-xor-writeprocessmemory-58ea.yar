rule TTP_XOR_WriteProcessMemory_58ea {
  strings:
    $key_58ea = { 0f 98 [2] 3d ba [2] 3b 8f [2] 15 8f [2] 2a 93 }

  condition:
    any of them
}