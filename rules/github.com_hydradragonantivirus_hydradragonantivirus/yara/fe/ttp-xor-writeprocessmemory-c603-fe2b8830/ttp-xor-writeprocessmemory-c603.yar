rule TTP_XOR_WriteProcessMemory_c603 {
  strings:
    $key_c603 = { 91 71 [2] a3 53 [2] a5 66 [2] 8b 66 [2] b4 7a }

  condition:
    any of them
}