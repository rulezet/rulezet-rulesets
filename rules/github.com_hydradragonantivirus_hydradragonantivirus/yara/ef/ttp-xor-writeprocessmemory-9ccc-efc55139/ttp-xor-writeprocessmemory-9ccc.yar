rule TTP_XOR_WriteProcessMemory_9ccc {
  strings:
    $key_9ccc = { cb be [2] f9 9c [2] ff a9 [2] d1 a9 [2] ee b5 }

  condition:
    any of them
}