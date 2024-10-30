if(typeof(iflychat_chatcamp_check) === "undefined" || iflychat_chatcamp_check === "0") {
  var iflychat_popup=document.createElement("DIV");
  iflychat_popup.className="iflychat-popup";
  document.body.appendChild(iflychat_popup);
}
else if(iflychat_chatcamp_check === "1") {
  var iflychat_popup=document.createElement("DIV");
  iflychat_popup.className="cc-side-chat-app";
  // iflychat_popup.setAttribute('data-height', '600px');
  // iflychat_popup.setAttribute('data-width', '370px');
  document.body.appendChild(iflychat_popup);
}