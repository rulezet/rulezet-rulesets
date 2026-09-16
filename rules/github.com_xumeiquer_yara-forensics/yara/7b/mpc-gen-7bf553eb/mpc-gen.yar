rule mpc_gen: MPC
{
    meta:
        author = "Rafa Bono"
        file_info = "Musepack encoded audio (generic)"

    strings:
        $a = {4D 50 2B}

    condition:
       $a at 0
}