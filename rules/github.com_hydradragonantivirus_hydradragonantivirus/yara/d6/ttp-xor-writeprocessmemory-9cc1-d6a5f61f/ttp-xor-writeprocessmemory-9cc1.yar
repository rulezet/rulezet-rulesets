rule TTP_XOR_WriteProcessMemory_9cc1 {
  strings:
    $key_9cc1 = { cb b3 [2] f9 91 [2] ff a4 [2] d1 a4 [2] ee b8 }

  condition:
    any of them
}