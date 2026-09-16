rule TTP_XOR_WriteProcessMemory_9cbf {
  strings:
    $key_9cbf = { cb cd [2] f9 ef [2] ff da [2] d1 da [2] ee c6 }

  condition:
    any of them
}