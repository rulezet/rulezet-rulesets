rule TTP_XOR_WriteProcessMemory_9cc8 {
  strings:
    $key_9cc8 = { cb ba [2] f9 98 [2] ff ad [2] d1 ad [2] ee b1 }

  condition:
    any of them
}