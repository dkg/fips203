use fips203;

#[repr(C)]
pub struct ml_kem_shared_secret {
    data: [u8; fips203::SSK_LEN],
}

// ML-KEM-512

#[repr(C)]
pub struct ml_kem_512_encaps_key {
    data: [u8; fips203::ml_kem_512::EK_LEN],
}
#[repr(C)]
pub struct ml_kem_512_decaps_key {
    data: [u8; fips203::ml_kem_512::DK_LEN],
}
#[repr(C)]
pub struct ml_kem_512_ciphertext {
    data: [u8; fips203::ml_kem_512::CT_LEN],
}

#[no_mangle]
pub extern "C" fn ml_kem_512_keygen(encaps_out: Option<&mut ml_kem_512_encaps_key>,
                                    decaps_out: Option<&mut ml_kem_512_decaps_key>) -> bool {
    use fips203::traits::{KeyGen, SerDes};

    if let (Some(encaps_out), Some(decaps_out)) = (encaps_out, decaps_out) {
        let (ek, dk) = fips203::ml_kem_512::KG::try_keygen_vt().unwrap();
        encaps_out.data = ek.into_bytes();
        decaps_out.data = dk.into_bytes();
        return true;
    } else {
        return false;
    }
}

#[no_mangle]
pub extern "C" fn ml_kem_512_encaps(encaps: Option<&ml_kem_512_encaps_key>,
                                    ciphertext_out: Option<&mut ml_kem_512_ciphertext>,
                                    shared_secret_out: Option<&mut ml_kem_shared_secret>) -> bool {
    use fips203::traits::{Encaps, SerDes};

    if let (Some(encaps), Some(ciphertext_out), Some(shared_secret_out)) = (encaps, ciphertext_out, shared_secret_out) {
        let ek = fips203::ml_kem_512::EncapsKey::try_from_bytes(encaps.data).unwrap();
        let (ssk, ct) = ek.try_encaps_vt().unwrap();
        shared_secret_out.data = ssk.into_bytes();
        ciphertext_out.data = ct.into_bytes();

        return true;
    } else {
        return false;
    }
}

#[no_mangle]
pub extern "C" fn ml_kem_512_decaps(decaps: Option<&ml_kem_512_decaps_key>,
                                    ciphertext: Option<&ml_kem_512_ciphertext>,
                                    shared_secret_out: Option<&mut ml_kem_shared_secret>) -> bool {
    use fips203::traits::{Decaps, SerDes};

    if let (Some(decaps), Some(ciphertext), Some(shared_secret_out)) = (decaps, ciphertext, shared_secret_out) {
        let dk = fips203::ml_kem_512::DecapsKey::try_from_bytes(decaps.data).unwrap();
        let ct = fips203::ml_kem_512::CipherText::try_from_bytes(ciphertext.data).unwrap();
        let ssk = dk.try_decaps_vt(&ct).unwrap();

        shared_secret_out.data = ssk.into_bytes();

        return true;
    } else {
        return false;
    }
}



// ML-KEM-768

#[repr(C)]
pub struct ml_kem_768_encaps_key {
    data: [u8; fips203::ml_kem_768::EK_LEN],
}
#[repr(C)]
pub struct ml_kem_768_decaps_key {
    data: [u8; fips203::ml_kem_768::DK_LEN],
}
#[repr(C)]
pub struct ml_kem_768_ciphertext {
    data: [u8; fips203::ml_kem_768::CT_LEN],
}

#[no_mangle]
pub extern "C" fn ml_kem_768_keygen(encaps_out: Option<&mut ml_kem_768_encaps_key>,
                                    decaps_out: Option<&mut ml_kem_768_decaps_key>) -> bool {
    use fips203::traits::{KeyGen, SerDes};

    if let (Some(encaps_out), Some(decaps_out)) = (encaps_out, decaps_out) {
        let (ek, dk) = fips203::ml_kem_768::KG::try_keygen_vt().unwrap();
        encaps_out.data = ek.into_bytes();
        decaps_out.data = dk.into_bytes();

        return true;
    } else {
        return false;
    }
}

#[no_mangle]
pub extern "C" fn ml_kem_768_encaps(encaps: Option<&ml_kem_768_encaps_key>,
                                    ciphertext_out: Option<&mut ml_kem_768_ciphertext>,
                                    shared_secret_out: Option<&mut ml_kem_shared_secret>) -> bool {
    use fips203::traits::{Encaps, SerDes};

    if let (Some(encaps), Some(ciphertext_out), Some(shared_secret_out)) = (encaps, ciphertext_out, shared_secret_out) {
        let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(encaps.data).unwrap();
        let (ssk, ct) = ek.try_encaps_vt().unwrap();
        shared_secret_out.data = ssk.into_bytes();
        ciphertext_out.data = ct.into_bytes();

        return true;
    } else {
        return false;
    }
}

#[no_mangle]
pub extern "C" fn ml_kem_768_decaps(decaps: Option<&ml_kem_768_decaps_key>,
                                    ciphertext: Option<&ml_kem_768_ciphertext>,
                                    shared_secret_out: Option<&mut ml_kem_shared_secret>) -> bool {
    use fips203::traits::{Decaps, SerDes};

    if let (Some(decaps), Some(ciphertext), Some(shared_secret_out)) = (decaps, ciphertext, shared_secret_out) {
        let dk = fips203::ml_kem_768::DecapsKey::try_from_bytes(decaps.data).unwrap();
        let ct = fips203::ml_kem_768::CipherText::try_from_bytes(ciphertext.data).unwrap();
        let ssk = dk.try_decaps_vt(&ct).unwrap();

        shared_secret_out.data = ssk.into_bytes();

        return true;
    } else {
        return false;
    }
}


// ML-KEM-1024

#[repr(C)]
pub struct ml_kem_1024_encaps_key {
    data: [u8; fips203::ml_kem_1024::EK_LEN],
}
#[repr(C)]
pub struct ml_kem_1024_decaps_key {
    data: [u8; fips203::ml_kem_1024::DK_LEN],
}
#[repr(C)]
pub struct ml_kem_1024_ciphertext {
    data: [u8; fips203::ml_kem_1024::CT_LEN],
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_keygen(encaps_out: Option<&mut ml_kem_1024_encaps_key>,
                                     decaps_out: Option<&mut ml_kem_1024_decaps_key>) -> bool {
    use fips203::traits::{KeyGen, SerDes};

    if let (Some(encaps_out), Some(decaps_out)) = (encaps_out, decaps_out) {
        let (ek, dk) = fips203::ml_kem_1024::KG::try_keygen_vt().unwrap();
        encaps_out.data = ek.into_bytes();
        decaps_out.data = dk.into_bytes();

        return true;
    } else {
        return false;
    }
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_encaps(encaps: Option<&ml_kem_1024_encaps_key>,
                                     ciphertext_out: Option<&mut ml_kem_1024_ciphertext>,
                                     shared_secret_out: Option<&mut ml_kem_shared_secret>) -> bool {
    use fips203::traits::{Encaps, SerDes};

    if let (Some(encaps), Some(ciphertext_out), Some(shared_secret_out)) = (encaps, ciphertext_out, shared_secret_out) {
        let ek = fips203::ml_kem_1024::EncapsKey::try_from_bytes(encaps.data).unwrap();
        let (ssk, ct) = ek.try_encaps_vt().unwrap();
        shared_secret_out.data = ssk.into_bytes();
        ciphertext_out.data = ct.into_bytes();

        return true;
    } else {
        return false;
    }
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_decaps(decaps: Option<&ml_kem_1024_decaps_key>,
                                     ciphertext: Option<&ml_kem_1024_ciphertext>,
                                     shared_secret_out: Option<&mut ml_kem_shared_secret>) -> bool {
    use fips203::traits::{Decaps, SerDes};

    if let (Some(decaps), Some(ciphertext), Some(shared_secret_out)) = (decaps, ciphertext, shared_secret_out) {
        let dk = fips203::ml_kem_1024::DecapsKey::try_from_bytes(decaps.data).unwrap();
        let ct = fips203::ml_kem_1024::CipherText::try_from_bytes(ciphertext.data).unwrap();
        let ssk = dk.try_decaps_vt(&ct).unwrap();

        shared_secret_out.data = ssk.into_bytes();

        return true;
    } else {
        return false;
    }
}
