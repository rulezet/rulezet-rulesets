rule TTP_XOR_WriteProcessMemory_c5ea {
  strings:
    $key_c5ea = { 92 98 [2] a0 ba [2] a6 8f [2] 88 8f [2] b7 93 }

  condition:
    any of them
}