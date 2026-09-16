rule TTP_XOR_WriteProcessMemory_cb9d {
  strings:
    $key_cb9d = { 9c ef [2] ae cd [2] a8 f8 [2] 86 f8 [2] b9 e4 }

  condition:
    any of them
}