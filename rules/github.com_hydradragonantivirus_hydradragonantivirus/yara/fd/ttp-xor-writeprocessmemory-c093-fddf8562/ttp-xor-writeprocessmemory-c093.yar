rule TTP_XOR_WriteProcessMemory_c093 {
  strings:
    $key_c093 = { 97 e1 [2] a5 c3 [2] a3 f6 [2] 8d f6 [2] b2 ea }

  condition:
    any of them
}