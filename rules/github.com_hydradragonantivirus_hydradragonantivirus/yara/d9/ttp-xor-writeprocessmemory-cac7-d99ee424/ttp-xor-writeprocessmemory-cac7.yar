rule TTP_XOR_WriteProcessMemory_cac7 {
  strings:
    $key_cac7 = { 9d b5 [2] af 97 [2] a9 a2 [2] 87 a2 [2] b8 be }

  condition:
    any of them
}