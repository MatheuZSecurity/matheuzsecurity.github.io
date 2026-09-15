// lightweight fuse.js search — standalone, no build params
(function () {
    var fuse, resultsAvailable = false;
    var resList = document.getElementById('searchResults');
    var sInput = document.getElementById('searchInput');
    if (!resList || !sInput) return;
    var first, last, current_elem = null;

    var indexUrl = new URL('index.json', window.location.origin + '/').href;

    fetch(indexUrl)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            fuse = new Fuse(data, {
                ignoreLocation: true,
                threshold: 0.4,
                distance: 100,
                minMatchCharLength: 2,
                keys: ['title', 'summary', 'content', 'permalink']
            });
        })
        .catch(function (e) { console.error('search index load failed', e); });

    function activeToggle(ae) {
        document.querySelectorAll('.focus').forEach(function (el) { el.classList.remove('focus'); });
        if (ae) { ae.focus(); current_elem = ae; ae.parentElement.classList.add('focus'); }
    }

    function reset() {
        resultsAvailable = false;
        resList.innerHTML = sInput.value = '';
        sInput.focus();
    }

    sInput.onkeyup = function () {
        if (!fuse) return;
        var results = fuse.search(this.value.trim(), { limit: 12 });
        if (results.length) {
            var html = '';
            for (var i = 0; i < results.length; i++) {
                var it = results[i].item;
                html += '<li><a href="' + it.permalink + '">' + it.title + ' &raquo;</a></li>';
            }
            resList.innerHTML = html;
            resultsAvailable = true;
            first = resList.firstChild;
            last = resList.lastChild;
        } else {
            resultsAvailable = false;
            resList.innerHTML = '';
        }
    };

    sInput.addEventListener('search', function () { if (!this.value) reset(); });

    document.onkeydown = function (e) {
        var key = e.key;
        var ae = document.activeElement;
        var inbox = document.getElementById('searchbox').contains(ae);
        if (ae === sInput) {
            var els = document.getElementsByClassName('focus');
            while (els.length > 0) els[0].classList.remove('focus');
        } else if (current_elem) { ae = current_elem; }

        if (key === 'Escape') { reset(); }
        else if (!resultsAvailable || !inbox) { return; }
        else if (key === 'ArrowDown') {
            e.preventDefault();
            if (ae === sInput) { activeToggle(resList.firstChild.firstChild); }
            else if (ae.parentElement !== last) { activeToggle(ae.parentElement.nextSibling.firstChild); }
        } else if (key === 'ArrowUp') {
            e.preventDefault();
            if (ae.parentElement === first) { activeToggle(sInput); }
            else if (ae !== sInput) { activeToggle(ae.parentElement.previousSibling.firstChild); }
        } else if (key === 'Enter' && current_elem) { current_elem.click(); }
    };
})();
