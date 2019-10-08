
function check_form()
    {
        var p1,p2,u;
        u=document.getElementById("username");  
        p1=document.getElementById("password");
        p2=document.getElementById("password_confirm");
        if(u.value=='')
        {
            document.getElementById("password_warning").innerHTML="Username cannot be empty";
            return false;
        }
        if(p1.value!=p2.value )
        {
            document.getElementById("password_warning").innerHTML="Passwords do not match.";
            return false;
        }
        if(p1.value.length<=3)
        {
            document.getElementById("password_warning").innerHTML="Password too short. At least 4 characters.";
            return false;
        }
}

$('#myModal').ready(
	function load_modal(){
		// Get the modal
		var modal = document.getElementById('myModal');
	
		// Get the <span> element that closes the modal
		var span = document.getElementsByClassName("close")[0];
		
		
		var btn = document.getElementById("loading");
		if (!btn || !modal) return;
		
		// When the user clicks on <span> (x), close the modal
		span.onclick = function() {
		    modal.style.display = "none";
		};
	
		// When the user clicks anywhere outside of the modal, close it
		window.onclick = function(event) {
		    if (event.target == modal) {
	       	 modal.style.display = "none";
	    	}
		};
	}
);

function loading_click(image_id, page) {
	var modal = document.getElementById('myModal');
	var btn = document.getElementById("loading");
	$('#delete_loading')[0].onclick = function () {
		location.href='./delete/?image_id='+image_id +'&page=' + page;
	};
	modal.style.display = "block";
	
}