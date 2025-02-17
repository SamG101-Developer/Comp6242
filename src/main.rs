mod engines;

fn main() {
    let ciphertext = String::from("Nw vx lzureyday dg ykvx vgfjr yr vswetghhh gmh atwvtq bk vhrpnylij dai ibwpnylij dfxhfxprswf. Ykr krerhe nv ns ‘dfxhfxprsw bk orfuanqt’ fqq ykr qdgyhe nv ‘nxvrxvzjqg kre qhnwqvsj’, jmlpm fnuwhwh gmh inwnq gvkirwhahh vs ihsfgnra. Ykr krerhe zvhfoyd wnphf uonhh ny wuj hai rs f fbzufj rs xwhib nsg vy lf rdvsol hrahheshq blgm ‘vhrpvsj hu’ zufw ufv ojha qhnwqri inhwf, uuvsfvuorx dai jrshefovxdgnrax, dcuovhdgnrax dai vxnoyx");

    let strat_time = std::time::Instant::now();
    let plaintext = engines::vigenere::crack(ciphertext);
    let end_time = strat_time.elapsed();

    println!("{} ({}us)", plaintext, end_time.as_micros());
}
