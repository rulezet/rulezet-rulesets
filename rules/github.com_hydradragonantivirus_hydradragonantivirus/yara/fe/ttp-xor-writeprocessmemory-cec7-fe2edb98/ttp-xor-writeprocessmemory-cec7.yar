rule TTP_XOR_WriteProcessMemory_cec7 {
  strings:
    $key_cec7 = { 99 b5 [2] ab 97 [2] ad a2 [2] 83 a2 [2] bc be }

  condition:
    any of them
}