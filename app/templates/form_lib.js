var sphere_count=0;
function add_sphere() {
  var form = document.getElementById("form");
	var sphere_counter=document.getElementById("sphere_count");
  var n=sphere_count.toString();
  var snippet= "<span id=\"sphere"+n+"\">"+
      "<label>Radius </label><input type=\"number\" step=\"any\" id=\"radius"+n+"\" /><br/>"+
      "<label>Center X </label><input type=\"number\" step=\"any\" id=\"center_x"+n+"\" /><br/>"+
      "<label>Center Y </label><input type=\"number\" step=\"any\" id=\"center_y"+n+"\" /><br/>"+
      "<label>Center Z </label><input type=\"number\" step=\"any\" id=\"center_z"+n+"\" /><br/>"+
      "<label>Color </label>R<input type=\"number\" step=\"any\" id=\"color_r"+n+"\" />G<input type=\"number\" step=\"any\" id=\"color_g"+n+"\" />B<input type=\"number\" step=\"any\" id=\"color_b"+n+"\" /><br/>"+
   "</span>";
   
   
   form.innerHTML+=snippet;
   form.innerHTML+=n;
   sphere_count=sphere_count+1;
	 
}