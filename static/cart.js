$(function () {
    'use strict';

    const KEY = window.CART_KEY || 'cart';
    const fmt = n => 'Rp ' + Number(n).toLocaleString('id-ID');

    // Keranjang disimpan di browser (localStorage), satu keranjang per akun.
    // Harga dan stok di sini hanya tampilan: server menghitung ulang saat checkout.
    function muat() {
        try {
            const data = JSON.parse(localStorage.getItem(KEY) || '[]');
            if (!Array.isArray(data)) return [];
            return data.filter(i => i && Number.isInteger(i.id) && Number.isInteger(i.q) && i.q > 0 &&
                typeof i.name === 'string' && Number.isFinite(i.price));
        } catch (e) {
            return [];
        }
    }

    let cart = window.CLEAR_CART ? [] : muat();

    function simpan() {
        try { localStorage.setItem(KEY, JSON.stringify(cart)); } catch (e) { /* diabaikan */ }
    }

    let timerToast;
    function toast(pesan) {
        const $t = $('#toast');
        $t.text(pesan).addClass('on');
        clearTimeout(timerToast);
        timerToast = setTimeout(() => $t.removeClass('on'), 1800);
    }

    function render() {
        $('#count').text(cart.reduce((a, i) => a + i.q, 0));

        // Semua teks dimasukkan lewat .text() supaya tidak ada HTML yang ikut tereksekusi
        const $box = $('#items').empty();
        if (!cart.length) {
            $box.append($('<p class="empty">').text('Keranjang masih kosong. Tambahkan boneka untuk mulai.'));
        }

        $.each(cart, function (k, i) {
            const $th = $('<div class="th">');
            if (i.img && i.img.indexOf('/static/') === 0) {
                $th.append($('<img>').attr({ src: i.img, alt: i.name }));
            }

            const $m = $('<div class="m">').text(i.name).append($('<small>').text(fmt(i.price)));

            const $kurang = $('<button type="button">').attr({ 'data-k': k, 'data-d': -1, 'aria-label': 'Kurangi' }).text('−');
            const $tambah = $('<button type="button">').attr({ 'data-k': k, 'data-d': 1, 'aria-label': 'Tambah' }).text('+');
            const $q = $('<div class="q">').append($kurang, document.createTextNode(String(i.q)), $tambah);

            $box.append($('<div class="it">').append($th, $m, $q));
        });

        $('#total').text(fmt(cart.reduce((a, i) => a + i.price * i.q, 0)));
        simpan();
    }

    // Tombol "Tambah ke keranjang" (di halaman toko dan halaman produk)
    $(document).on('click', '.add[data-id]', function () {
        const $b = $(this);
        if ($b.prop('disabled')) return;

        // .attr() dipakai (bukan .data()) agar nilainya tidak diubah jQuery jadi angka atau objek
        const id = parseInt($b.attr('data-id'), 10);
        const stok = parseInt($b.attr('data-stok'), 10) || 0;
        const item = cart.find(i => i.id === id);

        if (item) {
            if (item.q >= stok) { toast('Stok hanya ' + stok); return; }
            item.q++;
            item.stok = stok;
        } else {
            cart.push({
                id: id,
                name: $b.attr('data-name') || '',
                price: parseInt($b.attr('data-price'), 10),
                img: $b.attr('data-img') || '',
                stok: stok,
                q: 1
            });
        }
        render();
        toast('Ditambahkan ke keranjang');
    });

    // Tombol + dan - di dalam keranjang
    $('#items').on('click', 'button[data-k]', function () {
        const k = parseInt($(this).attr('data-k'), 10);
        const d = parseInt($(this).attr('data-d'), 10);
        const i = cart[k];
        if (!i) return;
        if (d > 0 && i.stok && i.q >= i.stok) { toast('Stok hanya ' + i.stok); return; }
        i.q += d;
        if (i.q < 1) cart.splice(k, 1);
        render();
    });

    // Buka dan tutup panel keranjang
    const buka = v => $('body').toggleClass('open', v);
    $('#openCart').on('click', () => buka(true));
    $('#closeCart, #shade').on('click', () => buka(false));
    $(document).on('keydown', e => { if (e.key === 'Escape') buka(false); });

    // Checkout: kirim hanya id dan jumlah ke server
    $('#formCheckout').on('submit', function (e) {
        if (!cart.length) {
            e.preventDefault();
            toast('Keranjang masih kosong');
            return;
        }
        $('#itemsInput').val(JSON.stringify(cart.map(i => ({ id: i.id, q: i.q }))));
    });

    render();
});