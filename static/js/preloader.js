document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('formId').addEventListener('click', function(event) {
        var preloader = document.querySelector('.preloader-wrapper');
        preloader.style.display = 'block';

        setTimeout(function() {
            preloader.style.display = 'none';
        }, 2000);
    });
});
