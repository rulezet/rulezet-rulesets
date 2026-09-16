rule TTP_XOR_WriteProcessMemory_caac {
  strings:
    $key_caac = { 9d de [2] af fc [2] a9 c9 [2] 87 c9 [2] b8 d5 }

  condition:
    any of them
}