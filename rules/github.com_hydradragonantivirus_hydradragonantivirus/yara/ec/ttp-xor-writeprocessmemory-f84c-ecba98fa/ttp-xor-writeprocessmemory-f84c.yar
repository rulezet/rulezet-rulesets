rule TTP_XOR_WriteProcessMemory_f84c {
  strings:
    $key_f84c = { af 3e [2] 9d 1c [2] 9b 29 [2] b5 29 [2] 8a 35 }

  condition:
    any of them
}