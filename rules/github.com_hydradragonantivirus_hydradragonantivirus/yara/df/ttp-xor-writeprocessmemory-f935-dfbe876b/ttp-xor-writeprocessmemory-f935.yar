rule TTP_XOR_WriteProcessMemory_f935 {
  strings:
    $key_f935 = { ae 47 [2] 9c 65 [2] 9a 50 [2] b4 50 [2] 8b 4c }

  condition:
    any of them
}