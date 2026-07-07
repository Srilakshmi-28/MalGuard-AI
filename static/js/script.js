const fileInput = document.getElementById("fileInput");
const selectedFile = document.getElementById("selectedFile");

if(fileInput){

    fileInput.addEventListener("change", function(){

        if(this.files.length > 0){

            selectedFile.innerHTML =
                "Selected File : <b>" + this.files[0].name + "</b>";

        }

    });

}