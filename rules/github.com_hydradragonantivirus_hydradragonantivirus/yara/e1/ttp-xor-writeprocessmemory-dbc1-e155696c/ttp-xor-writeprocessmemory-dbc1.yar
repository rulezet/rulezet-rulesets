rule TTP_XOR_WriteProcessMemory_dbc1 {
  strings:
    $key_dbc1 = { 8c b3 [2] be 91 [2] b8 a4 [2] 96 a4 [2] a9 b8 }

  condition:
    any of them
}