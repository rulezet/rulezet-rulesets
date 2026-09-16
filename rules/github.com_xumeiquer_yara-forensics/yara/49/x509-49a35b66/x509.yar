rule x509: DER x509
{
    meta:
        author = "Jaume Martin"
        
    strings:
        $a = {30 82}

    condition:
       $a at 0
}