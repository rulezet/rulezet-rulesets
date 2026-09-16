rule TTP_XOR_WriteProcessMemory_f203 {
  strings:
    $key_f203 = { a5 71 [2] 97 53 [2] 91 66 [2] bf 66 [2] 80 7a }

  condition:
    any of them
}