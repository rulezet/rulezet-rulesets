rule TTP_XOR_WriteProcessMemory_bcbf {
  strings:
    $key_bcbf = { eb cd [2] d9 ef [2] df da [2] f1 da [2] ce c6 }

  condition:
    any of them
}