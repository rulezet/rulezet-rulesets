rule TTP_XOR_WriteProcessMemory_caa8 {
  strings:
    $key_caa8 = { 9d da [2] af f8 [2] a9 cd [2] 87 cd [2] b8 d1 }

  condition:
    any of them
}