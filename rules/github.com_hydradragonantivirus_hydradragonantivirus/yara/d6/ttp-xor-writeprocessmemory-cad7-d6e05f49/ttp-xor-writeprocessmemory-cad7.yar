rule TTP_XOR_WriteProcessMemory_cad7 {
  strings:
    $key_cad7 = { 9d a5 [2] af 87 [2] a9 b2 [2] 87 b2 [2] b8 ae }

  condition:
    any of them
}