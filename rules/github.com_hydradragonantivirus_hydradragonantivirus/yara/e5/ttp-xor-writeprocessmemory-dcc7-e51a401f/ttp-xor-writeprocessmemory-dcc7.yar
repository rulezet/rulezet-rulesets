rule TTP_XOR_WriteProcessMemory_dcc7 {
  strings:
    $key_dcc7 = { 8b b5 [2] b9 97 [2] bf a2 [2] 91 a2 [2] ae be }

  condition:
    any of them
}