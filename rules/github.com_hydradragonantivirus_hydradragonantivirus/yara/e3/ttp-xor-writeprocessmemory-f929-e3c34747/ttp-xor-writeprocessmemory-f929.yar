rule TTP_XOR_WriteProcessMemory_f929 {
  strings:
    $key_f929 = { ae 5b [2] 9c 79 [2] 9a 4c [2] b4 4c [2] 8b 50 }

  condition:
    any of them
}