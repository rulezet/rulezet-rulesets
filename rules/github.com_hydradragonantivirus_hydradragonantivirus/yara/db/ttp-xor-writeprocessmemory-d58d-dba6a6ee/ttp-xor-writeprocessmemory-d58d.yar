rule TTP_XOR_WriteProcessMemory_d58d {
  strings:
    $key_d58d = { 82 ff [2] b0 dd [2] b6 e8 [2] 98 e8 [2] a7 f4 }

  condition:
    any of them
}