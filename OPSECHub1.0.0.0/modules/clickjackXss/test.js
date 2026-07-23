document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('btn-load');
    const input = document.getElementById('target-url');
    const wrapper = document.getElementById('frame-wrapper');
    
    if (btn && input && wrapper) {
        btn.addEventListener('click', () => {
            let url = input.value.trim();
            if (!url) return;
            
            // Security hardening: Force http/https protocols only to prevent protocol handler exploits (e.g. javascript:, data:)
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
            }
            
            // Clear and inject iframe safely using strict DOM creation
            wrapper.replaceChildren();
            const iframe = document.createElement('iframe');
            iframe.src = url;
            wrapper.appendChild(iframe);
        });
    }
});
