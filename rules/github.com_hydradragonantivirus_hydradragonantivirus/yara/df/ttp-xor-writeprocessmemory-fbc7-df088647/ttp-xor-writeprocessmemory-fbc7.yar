rule TTP_XOR_WriteProcessMemory_fbc7 {
  strings:
    $key_fbc7 = { ac b5 [2] 9e 97 [2] 98 a2 [2] b6 a2 [2] 89 be }

  condition:
    any of them
}