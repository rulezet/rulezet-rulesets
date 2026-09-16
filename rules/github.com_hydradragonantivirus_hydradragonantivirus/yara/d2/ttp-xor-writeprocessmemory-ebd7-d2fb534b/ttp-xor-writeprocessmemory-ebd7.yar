rule TTP_XOR_WriteProcessMemory_ebd7 {
  strings:
    $key_ebd7 = { bc a5 [2] 8e 87 [2] 88 b2 [2] a6 b2 [2] 99 ae }

  condition:
    any of them
}