rule TTP_XOR_WriteProcessMemory_504c {
  strings:
    $key_504c = { 07 3e [2] 35 1c [2] 33 29 [2] 1d 29 [2] 22 35 }

  condition:
    any of them
}